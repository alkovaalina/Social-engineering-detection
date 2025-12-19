import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np
import math
import pandas as pd

with open('questions.txt', 'r', encoding='utf-8') as f:
    questions = [line.strip() for line in f if line.strip()]

df = pd.read_excel('weight_matrix.xlsx', sheet_name='norm_weight_matrix')
W = df.iloc[:, 1:].values

scenarios = [
    "Phishing (Email/Website)",
    "Spear-phishing",
    "Baiting",
    "Water-Holing",
    "Pretexting"
]

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SE Incident Detection Gap Analyzer")
        self.root.geometry("800x400")

        self.questions_per_page = 5
        self.total_pages = math.ceil(len(questions) / self.questions_per_page)
        self.current_page = 0
        self.score_vars = [tk.IntVar(value=1) for _ in questions]

        style = ttk.Style()
        style.configure("TLabel", font=("Arial", 10))
        style.configure("TButton", font=("Arial", 12, "bold"))

        self.question_frame = ttk.Frame(root, padding=20)
        self.question_frame.pack(fill="both", expand=True)

        self.progress_label = ttk.Label(self.question_frame, text="")
        self.progress_label.pack(pady=10)

        self.progress = ttk.Progressbar(
            self.question_frame, orient="horizontal",
            length=300, maximum=self.total_pages
        )
        self.progress.pack(pady=10)

        self.page_frame = ttk.Frame(self.question_frame)
        self.page_frame.pack(fill="x", pady=10)

        self.buttons_frame = ttk.Frame(self.question_frame)
        self.buttons_frame.pack(pady=10)

        self.prev_button = ttk.Button(self.buttons_frame, text="Попередня сторінка", command=self.prev_page)
        self.prev_button.grid(row=0, column=0, padx=10)

        self.next_button = ttk.Button(self.buttons_frame, text="Наступна сторінка", command=self.next_page)
        self.next_button.grid(row=0, column=1, padx=10)

        self.result_frame = ttk.Frame(root, padding=20)
        self.result_text = tk.Text(self.result_frame, height=15, wrap="word", font=("Consolas", 11))
        self.result_text.pack(fill="both", expand=True)
        self.result_text.config(state="disabled")

        self.back_button = ttk.Button(self.result_frame, text="Назад", command=self.back_to_questions)
        self.back_button.pack(pady=10)

        self.build_page()

    def validate_scores(self):
        for idx, var in enumerate(self.score_vars, start=1):
            val = var.get()
            if not (1 <= val <= 5):
                messagebox.showerror(
                    "Помилка",
                    f"У питанні №{idx} вказано некоректну оцінку: {val}.\n"
                    "Допустимий діапазон — 1–5."
                )
                return False
        return True

    def build_page(self):
        for widget in self.page_frame.winfo_children():
            widget.destroy()

        start = self.current_page * self.questions_per_page
        end = min(start + self.questions_per_page, len(questions))

        for i in range(start, end):
            ttk.Label(self.page_frame, text=questions[i], wraplength=700, justify="left")\
                .grid(row=i - start, column=0, padx=5, pady=5, sticky="w")

            ttk.Spinbox(self.page_frame, from_=1, to=5, textvariable=self.score_vars[i], width=5)\
                .grid(row=i - start, column=1, padx=5, pady=5)

        self.progress['value'] = self.current_page + 1
        self.progress_label.config(text=f"Сторінка {self.current_page + 1} з {self.total_pages}")

        self.prev_button.config(state="disabled" if self.current_page == 0 else "normal")
        self.next_button.config(text="Обчислити" if self.current_page == self.total_pages - 1 else "Наступна сторінка")

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.build_page()

    def next_page(self):
        if not self.validate_scores():
            return
        if self.current_page < self.total_pages - 1:
            self.current_page += 1
            self.build_page()
        else:
            self.calculate()

    def calculate(self):
        if not self.validate_scores():
            return

        scores = np.array([v.get() for v in self.score_vars])
        norm_scores = scores / 5.0

        DP = np.clip(np.dot(norm_scores, W), 0, 1)
        Pnd = 1 - DP

        result = "Результати оцінки ризику пропуску атаки\n\n"
        result += "═" * 82 + "\n"
        result += f"{'Сценарій соціальної інженерії':<48} {'Pnd':>10} {'Рівень ризику':>20}\n"
        result += "═" * 82 + "\n"

        risk_levels = []
        for scenario, p in zip(scenarios, Pnd):
            if p > 0.7:
                risk = "КРИТИЧНИЙ"
                tag = "critical"
            elif p > 0.5:
                risk = "ВИСОКИЙ"
                tag = "high"
            elif p > 0.3:
                risk = "Середній"
                tag = "medium"
            else:
                risk = "Низький"
                tag = "low"

            result += f"{scenario:<48} {p:>9.4f}     {risk:^12}\n"
            risk_levels.append((scenario, tag))

        result += "═" * 82 + "\n\n"

        self.question_frame.pack_forget()
        self.result_frame.pack(fill="both", expand=True)

        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)

        colors = {
            "critical": "#FF0000",
            "high": "#FF5500",
            "medium": "#FFAA00",
            "low": "#00AA00"
        }
        for tag, color in colors.items():
            self.result_text.tag_configure(tag, foreground=color, font=("Consolas", 11, "bold"))

        for scenario, tag in risk_levels:
            pos = "1.0"
            while True:
                pos = self.result_text.search(scenario, pos, tk.END)
                if not pos:
                    break
                line_end = pos.split('.')[0] + ".end"
                self.result_text.tag_add(tag, pos, line_end)
                pos = line_end

        self.result_text.config(state="disabled")

    def back_to_questions(self):
        self.result_frame.pack_forget()
        self.question_frame.pack(fill="both", expand=True)
        self.build_page()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
